from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from .config import ExportSettings, FalconCredentials


class FalconAlertsError(RuntimeError):
    """Readable error for CrowdStrike Alerts API collection failures."""


@dataclass
class CollectionResult:
    alerts: list[dict[str, Any]]
    pages: int
    truncated: bool
    fql_filter: str


def _body(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get("body") if isinstance(response, dict) else None
    return body if isinstance(body, dict) else {}


def _resources(response: dict[str, Any]) -> list[dict[str, Any]]:
    resources = _body(response).get("resources") or []
    return [item for item in resources if isinstance(item, dict)]


def _after_token(response: dict[str, Any]) -> str | None:
    pagination = (_body(response).get("meta") or {}).get("pagination") or {}
    value = pagination.get("after")
    return str(value) if value not in (None, "") else None


def _error_message(response: dict[str, Any]) -> str:
    body = _body(response)
    errors = body.get("errors") or []
    if isinstance(errors, list) and errors:
        parts: list[str] = []
        for error in errors[:5]:
            if isinstance(error, dict):
                parts.append(str(error.get("message") or error.get("code") or error))
            else:
                parts.append(str(error))
        return "; ".join(parts)
    return str(body or response)


class FalconAlertCollector:
    """Pull alerts using FalconPy Alerts.get_alerts_combined.

    CrowdStrike scope required: Alerts = READ.
    """

    def __init__(
        self,
        credentials: FalconCredentials,
        *,
        service: Any | None = None,
        max_retries: int = 5,
        retry_base_seconds: float = 1.0,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        self.credentials = credentials
        self.max_retries = max_retries
        self.retry_base_seconds = retry_base_seconds
        self._service = service
        self.progress_callback = progress_callback

    def _service_instance(self) -> Any:
        if self._service is not None:
            return self._service
        try:
            from falconpy import Alerts
        except Exception as exc:  # pragma: no cover
            raise FalconAlertsError(
                "FalconPy belum terpasang. Jalankan setup.bat atau "
                "pip install crowdstrike-falconpy."
            ) from exc
        self._service = Alerts(**self.credentials.falconpy_kwargs())
        return self._service

    def _call_with_retry(self, call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        last_response: dict[str, Any] | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = call()
            except Exception as exc:
                if attempt >= self.max_retries:
                    raise FalconAlertsError(f"Falcon API request gagal: {exc}") from exc
                wait = self.retry_base_seconds * (2**attempt)
                print(f"Request gagal, ulang dalam {wait:.0f} detik...")
                time.sleep(wait)
                continue

            last_response = response
            status_code = int(response.get("status_code") or 0)
            if 200 <= status_code < 300:
                return response

            if status_code in {401, 403}:
                raise FalconAlertsError(
                    f"Falcon Alerts API menolak akses (HTTP {status_code}). "
                    "Periksa Client ID/Secret, cloud region, Member CID, dan scope Alerts: READ. "
                    f"Detail: {_error_message(response)}"
                )

            retryable = status_code in {429, 500, 502, 503, 504}
            if not retryable or attempt >= self.max_retries:
                raise FalconAlertsError(
                    f"Falcon Alerts API error HTTP {status_code}: {_error_message(response)}"
                )

            wait = self.retry_base_seconds * (2**attempt)
            print(f"Falcon API HTTP {status_code}, ulang dalam {wait:.0f} detik...")
            time.sleep(wait)

        raise FalconAlertsError(f"Falcon API request gagal: {last_response}")

    def collect(self, settings: ExportSettings) -> CollectionResult:
        settings.validate()
        service = self._service_instance()
        fql_filter = settings.build_fql()
        after: str | None = None
        pages = 0
        output: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        while True:
            kwargs: dict[str, Any] = {
                "filter": fql_filter,
                "limit": settings.page_size,
                "sort": f"{settings.time_field}|asc",
            }
            if after:
                kwargs["after"] = after

            response = self._call_with_retry(
                lambda kwargs=kwargs: service.get_alerts_combined(**kwargs)
            )
            pages += 1
            resources = _resources(response)

            for resource_index, alert in enumerate(resources):
                stable_id = str(
                    alert.get("composite_id")
                    or alert.get("id")
                    or alert.get("aggregate_id")
                    or ""
                )
                if stable_id and stable_id in seen_ids:
                    continue
                if stable_id:
                    seen_ids.add(stable_id)
                output.append(alert)

                if len(output) >= settings.max_records:
                    truncated = (
                        resource_index < len(resources) - 1
                        or bool(_after_token(response))
                    )
                    if self.progress_callback:
                        self.progress_callback(pages, len(output))
                    return CollectionResult(
                        alerts=output[: settings.max_records],
                        pages=pages,
                        truncated=truncated,
                        fql_filter=fql_filter,
                    )

            if self.progress_callback:
                self.progress_callback(pages, len(output))

            after = _after_token(response)
            if not resources or not after:
                break

        return CollectionResult(
            alerts=output,
            pages=pages,
            truncated=False,
            fql_filter=fql_filter,
        )
