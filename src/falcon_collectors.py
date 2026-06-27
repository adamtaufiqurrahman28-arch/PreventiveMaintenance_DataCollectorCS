from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any, Callable
from zoneinfo import ZoneInfo

import pandas as pd

from .config import FalconConnection
from .utils import (
    body,
    chunks,
    ensure_success,
    errors,
    pagination_after,
    pagination_offset,
    pagination_total,
    resources,
)


ProgressCallback = Callable[[str], None]


@dataclass(slots=True)
class CollectionResult:
    records: list[dict[str, Any]]
    metadata: dict[str, Any]


def _require_falconpy() -> None:
    try:
        import falconpy  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "FalconPy belum terinstall. Jalankan: pip install crowdstrike-falconpy"
        ) from exc


def _notify(callback: ProgressCallback | None, message: str) -> None:
    if callback:
        callback(message)


def test_connections(conn: FalconConnection) -> dict[str, dict[str, Any]]:
    """Test the three read-only service collections used by this application."""
    _require_falconpy()
    from falconpy import Alerts, Hosts, PreventionPolicy

    checks: dict[str, dict[str, Any]] = {}

    services = {
        "Hosts: Read": lambda: Hosts(**conn.falconpy_kwargs()).query_devices_by_filter_scroll(limit=1),
        "Prevention Policies: Read": lambda: PreventionPolicy(**conn.falconpy_kwargs()).query_combined_policies(limit=1),
        "Alerts: Read": lambda: Alerts(**conn.falconpy_kwargs()).query_alerts_v2(limit=1),
    }
    for label, call in services.items():
        try:
            response = call()
            code = int(response.get("status_code") or 0)
            checks[label] = {
                "ok": 200 <= code < 300 and not errors(response),
                "status_code": code,
                "errors": errors(response),
            }
        except Exception as exc:  # pragma: no cover - live API only
            checks[label] = {"ok": False, "status_code": 0, "errors": [str(exc)]}
    return checks


def collect_hosts(
    conn: FalconConnection,
    *,
    fql_filter: str | None = None,
    max_records: int | None = None,
    page_size: int = 5000,
    include_online_state: bool = True,
    progress: ProgressCallback | None = None,
) -> CollectionResult:
    """Collect all host IDs with scroll pagination, then retrieve full details.

    Uses ``query_devices_by_filter_scroll`` followed by ``post_device_details_v2``.
    """
    _require_falconpy()
    from falconpy import Hosts

    service = Hosts(**conn.falconpy_kwargs())
    ids: list[str] = []
    offset: str | int | None = None
    query_pages = 0
    requested_limit = max(1, min(int(page_size), 5000))

    while True:
        params: dict[str, Any] = {"limit": requested_limit}
        if fql_filter:
            params["filter"] = fql_filter
        if offset not in (None, ""):
            params["offset"] = offset
        response = service.query_devices_by_filter_scroll(**params)
        ensure_success(response, "Query host")
        page = [str(item) for item in resources(response)]
        query_pages += 1
        ids.extend(page)
        _notify(progress, f"Host IDs: {len(ids):,} record ({query_pages} page)")
        offset = pagination_offset(response)
        if not page or offset in (None, ""):
            break
        if max_records and len(ids) >= max_records:
            ids = ids[:max_records]
            break

    details: list[dict[str, Any]] = []
    detail_batches = 0
    for batch in chunks(ids, 5000):
        response = service.post_device_details_v2(ids=batch)
        ensure_success(response, "Ambil detail host")
        page = [item for item in resources(response) if isinstance(item, dict)]
        details.extend(page)
        detail_batches += 1
        _notify(progress, f"Host detail: {len(details):,}/{len(ids):,}")

    online_state: dict[str, str] = {}
    if include_online_state and ids:
        for batch in chunks(ids, 100):
            try:
                response = service.get_online_state(ids=batch)
                ensure_success(response, "Ambil online state")
                for item in resources(response):
                    if isinstance(item, dict):
                        aid = str(item.get("id") or item.get("device_id") or "")
                        if aid:
                            online_state[aid] = str(item.get("state") or item.get("online_state") or "")
            except Exception as exc:  # Online state is supplementary, not fatal.
                _notify(progress, f"Online state dilewati: {exc}")
                break

    if online_state:
        for record in details:
            aid = str(record.get("device_id") or record.get("id") or "")
            record["online_state_api"] = online_state.get(aid, "")

    return CollectionResult(
        records=details,
        metadata={
            "collector": "Hosts API",
            "query_pages": query_pages,
            "detail_batches": detail_batches,
            "ids_found": len(ids),
            "records_collected": len(details),
            "filter": fql_filter or "*",
            "source": "CrowdStrike Hosts API — PostDeviceDetailsV2",
            "extraction_utc": datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


def collect_prevention_policies(
    conn: FalconConnection,
    *,
    fql_filter: str | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[CollectionResult, CollectionResult]:
    """Collect prevention policies and their full member records."""
    _require_falconpy()
    from falconpy import PreventionPolicy

    service = PreventionPolicy(**conn.falconpy_kwargs())
    policies: list[dict[str, Any]] = []
    offset: int | str | None = 0
    pages = 0

    while True:
        params: dict[str, Any] = {"limit": 5000}
        if fql_filter:
            params["filter"] = fql_filter
        if offset not in (None, "", 0):
            params["offset"] = offset
        response = service.query_combined_policies(**params)
        ensure_success(response, "Ambil Prevention Policies")
        page = [item for item in resources(response) if isinstance(item, dict)]
        policies.extend(page)
        pages += 1
        _notify(progress, f"Prevention policy: {len(policies):,} group")
        next_offset = pagination_offset(response)
        total = pagination_total(response)
        if not page or next_offset in (None, "") or (total is not None and len(policies) >= total):
            break
        if str(next_offset) == str(offset):
            break
        offset = next_offset

    # Retrieve full policy entities by ID as a second pass. Some tenants return a
    # reduced combined payload, while get_policies exposes the complete settings.
    policy_ids = [str(item.get("id") or item.get("policy_id") or "") for item in policies]
    policy_ids = [item for item in policy_ids if item]
    detailed_by_id: dict[str, dict[str, Any]] = {}
    for batch in chunks(policy_ids, 100):
        response = service.get_policies(ids=batch)
        ensure_success(response, "Ambil detail Prevention Policy")
        for item in resources(response):
            if isinstance(item, dict):
                item_id = str(item.get("id") or item.get("policy_id") or "")
                if item_id:
                    detailed_by_id[item_id] = item
    if detailed_by_id:
        merged_policies: list[dict[str, Any]] = []
        for policy in policies:
            policy_id = str(policy.get("id") or policy.get("policy_id") or "")
            detailed = detailed_by_id.get(policy_id)
            if detailed:
                merged = dict(policy)
                merged.update(detailed)
                merged_policies.append(merged)
            else:
                merged_policies.append(policy)
        policies = merged_policies

    members: list[dict[str, Any]] = []
    for policy_index, policy in enumerate(policies, start=1):
        policy_id = str(policy.get("id") or policy.get("policy_id") or "")
        if not policy_id:
            continue
        member_offset: int | str | None = 0
        member_count = 0
        while True:
            params = {"id": policy_id, "limit": 5000}
            if member_offset not in (None, "", 0):
                params["offset"] = member_offset
            response = service.query_combined_policy_members(**params)
            ensure_success(response, f"Ambil member policy {policy_id}")
            page = [item for item in resources(response) if isinstance(item, dict)]
            for item in page:
                item = dict(item)
                item["_policy_id"] = policy_id
                item["_policy_name"] = policy.get("name") or ""
                item["_policy_platform"] = policy.get("platform_name") or policy.get("platform") or ""
                members.append(item)
            member_count += len(page)
            next_offset = pagination_offset(response)
            total = pagination_total(response)
            if not page or next_offset in (None, "") or (total is not None and member_count >= total):
                break
            if str(next_offset) == str(member_offset):
                break
            member_offset = next_offset
        policy["_member_count_collected"] = member_count
        _notify(progress, f"Policy member: {policy_index}/{len(policies)} — {policy.get('name', policy_id)} = {member_count:,} host")

    return (
        CollectionResult(
            records=policies,
            metadata={
                "collector": "Prevention Policy API",
                "pages": pages,
                "records_collected": len(policies),
                "filter": fql_filter or "*",
            },
        ),
        CollectionResult(
            records=members,
            metadata={
                "collector": "Prevention Policy Members API",
                "records_collected": len(members),
                "policy_count": len(policies),
            },
        ),
    )


def build_alert_date_filter(
    start_date: date,
    end_date: date,
    *,
    timezone_name: str = "Asia/Jakarta",
    time_field: str = "created_timestamp",
    additional_fql: str | None = None,
) -> tuple[str, datetime, datetime]:
    if end_date < start_date:
        raise ValueError("Tanggal akhir tidak boleh sebelum tanggal awal.")
    zone = ZoneInfo(timezone_name)
    local_start = datetime.combine(start_date, time.min, tzinfo=zone)
    local_end_exclusive = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=zone)
    utc_start = local_start.astimezone(ZoneInfo("UTC"))
    utc_end = local_end_exclusive.astimezone(ZoneInfo("UTC"))
    start_text = utc_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_text = utc_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    base = f"{time_field}:>='{start_text}'+{time_field}:<'{end_text}'"
    if additional_fql and additional_fql.strip():
        base = f"({base})+({additional_fql.strip()})"
    return base, utc_start, utc_end


def _alert_expected_total(service: Any, fql_filter: str, include_hidden: bool) -> int | None:
    params: dict[str, Any] = {"filter": fql_filter, "limit": 1}
    if include_hidden:
        params["include_hidden"] = "true"
    response = service.query_alerts_v2(**params)
    ensure_success(response, "Hitung total alert")
    return pagination_total(response)



def _is_request_too_large(response: dict[str, Any] | None) -> bool:
    """Return True when CrowdStrike reports a payload/page-size limit error.

    Falcon can return HTTP 400 while the embedded error code is 413, so both
    the numeric error code and the message are inspected.
    """
    for item in errors(response):
        if isinstance(item, dict):
            try:
                if int(item.get("code") or 0) == 413:
                    return True
            except (TypeError, ValueError):
                pass
            message = str(item.get("message") or "").lower()
        else:
            message = str(item).lower()
        if "request too large" in message or "payload too large" in message:
            return True
    return False


def collect_alerts(
    conn: FalconConnection,
    *,
    start_date: date,
    end_date: date,
    timezone_name: str = "Asia/Jakarta",
    time_field: str = "created_timestamp",
    additional_fql: str | None = None,
    include_hidden: bool = False,
    max_records: int | None = None,
    page_size: int = 1000,
    progress: ProgressCallback | None = None,
) -> CollectionResult:
    """Collect Alerts API records only—never NGSIEM/CQL.

    Normal mode uses the combined endpoint with ``after`` pagination. When hidden
    alerts are requested, the collector switches to Query V2 + Entities V2 because
    ``include_hidden`` is exposed by Query V2.
    """
    _require_falconpy()
    from falconpy import Alerts

    service = Alerts(**conn.falconpy_kwargs())
    fql_filter, utc_start, utc_end = build_alert_date_filter(
        start_date,
        end_date,
        timezone_name=timezone_name,
        time_field=time_field,
        additional_fql=additional_fql,
    )
    expected_total = _alert_expected_total(service, fql_filter, include_hidden)
    if max_records and expected_total is not None:
        expected_for_run = min(expected_total, max_records)
    else:
        expected_for_run = expected_total

    records: list[dict[str, Any]] = []
    pages = 0
    mode = "Query V2 + Entities V2" if include_hidden else "Combined Alerts V1"

    if include_hidden:
        offset = 0
        query_limit = max(1, min(int(page_size), 10000))
        ids: list[str] = []
        while True:
            response = service.query_alerts_v2(
                filter=fql_filter,
                include_hidden="true",
                limit=query_limit,
                offset=offset,
                sort=f"{time_field}|asc",
            )
            ensure_success(response, "Query hidden alerts")
            page_ids = [str(item) for item in resources(response)]
            ids.extend(page_ids)
            pages += 1
            _notify(progress, f"Alert IDs: {len(ids):,}/{expected_for_run or '?'}")
            if not page_ids:
                break
            if max_records and len(ids) >= max_records:
                ids = ids[:max_records]
                break
            offset += len(page_ids)
            if expected_total is not None and offset >= expected_total:
                break
        for batch in chunks(ids, 100):
            response = service.get_alerts_v2(ids=batch)
            ensure_success(response, "Ambil detail hidden alert")
            records.extend(item for item in resources(response) if isinstance(item, dict))
            _notify(progress, f"Alert detail: {len(records):,}/{len(ids):,}")
    else:
        after: str | None = None
        # PostCombinedAlertsV1 documents a maximum page size of 1,000.
        # Some tenants can still reject a 1,000-record response when alert
        # entities are unusually large, so the collector automatically
        # reduces the page size and retries the same page.
        query_limit = max(1, min(int(page_size), 1000))
        initial_query_limit = query_limit
        minimum_query_limit = 25
        page_size_reductions = 0
        while True:
            params: dict[str, Any] = {
                "filter": fql_filter,
                "limit": query_limit,
                "sort": f"{time_field}|asc",
            }
            if after:
                params["after"] = after
            response = service.get_alerts_combined(**params)
            if _is_request_too_large(response):
                if query_limit <= minimum_query_limit:
                    ensure_success(response, "Ambil Alerts API")
                previous_limit = query_limit
                query_limit = max(minimum_query_limit, query_limit // 2)
                page_size_reductions += 1
                _notify(
                    progress,
                    f"Respons Alerts terlalu besar pada limit {previous_limit}; "
                    f"retry page yang sama dengan limit {query_limit}.",
                )
                continue
            ensure_success(response, "Ambil Alerts API")
            page = [item for item in resources(response) if isinstance(item, dict)]
            records.extend(page)
            pages += 1
            _notify(progress, f"Alerts: {len(records):,}/{expected_for_run or '?'}")
            if max_records and len(records) >= max_records:
                records = records[:max_records]
                break
            new_after = pagination_after(response)
            if not page or not new_after or new_after == after:
                break
            after = new_after

    # Remove duplicate composite IDs while preserving order.
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        identifier = str(
            record.get("composite_id")
            or record.get("id")
            or record.get("alert_id")
            or f"__row_{index}"
        )
        if identifier in seen:
            continue
        seen.add(identifier)
        unique.append(record)

    reconciliation = "Matched"
    if expected_for_run is not None and len(unique) != expected_for_run:
        reconciliation = "Difference Found"
    if max_records and expected_total and max_records < expected_total:
        reconciliation = "Limited by max_records"

    return CollectionResult(
        records=unique,
        metadata={
            "collector": "Alerts API",
            "mode": mode,
            "filter": fql_filter,
            "time_field": time_field,
            "timezone": timezone_name,
            "utc_start": utc_start.isoformat(),
            "utc_end_exclusive": utc_end.isoformat(),
            "include_hidden": include_hidden,
            "expected_total": expected_total,
            "records_collected": len(unique),
            "pages": pages,
            "requested_page_size": int(page_size),
            "initial_page_size": initial_query_limit if not include_hidden else query_limit,
            "effective_page_size": query_limit,
            "page_size_reductions": page_size_reductions if not include_hidden else 0,
            "reconciliation": reconciliation,
            "max_records": max_records,
        },
    )
