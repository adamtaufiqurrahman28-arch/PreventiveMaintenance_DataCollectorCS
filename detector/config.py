from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class FalconCredentials:
    client_id: str
    client_secret: str
    base_url: str = "us-1"
    member_cid: str | None = None

    @classmethod
    def from_env(cls) -> "FalconCredentials":
        client_id = (os.getenv("FALCON_CLIENT_ID") or "").strip()
        client_secret = (os.getenv("FALCON_CLIENT_SECRET") or "").strip()
        base_url = (os.getenv("FALCON_BASE_URL") or "us-1").strip()
        member_cid = (os.getenv("FALCON_MEMBER_CID") or "").strip() or None

        if not client_id or not client_secret:
            raise ValueError(
                "Credential belum lengkap. Isi FALCON_CLIENT_ID dan "
                "FALCON_CLIENT_SECRET pada file .env."
            )
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            member_cid=member_cid,
        )

    def falconpy_kwargs(self) -> dict[str, str]:
        kwargs = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "base_url": self.base_url,
        }
        if self.member_cid:
            kwargs["member_cid"] = self.member_cid
        return kwargs


@dataclass(frozen=True)
class ExportSettings:
    customer_name: str
    report_label: str
    start_date: date
    end_date: date
    utc_offset_hours: int = 7
    time_field: str = "created_timestamp"
    page_size: int = 1000
    max_records: int = 200_000
    top_n: int = 10
    additional_fql: str | None = None
    include_raw_json: bool = False

    def validate(self) -> None:
        if self.end_date < self.start_date:
            raise ValueError("Tanggal akhir tidak boleh lebih kecil dari tanggal awal.")
        if not -12 <= self.utc_offset_hours <= 14:
            raise ValueError("UTC offset harus berada di antara -12 dan +14.")
        if not 1 <= self.page_size <= 1000:
            raise ValueError("Page size Alerts API harus 1 sampai 1000.")
        if not 1 <= self.max_records <= 1_000_000:
            raise ValueError("Max records harus 1 sampai 1.000.000.")
        if self.time_field not in {
            "created_timestamp",
            "timestamp",
            "updated_timestamp",
        }:
            raise ValueError("time_field tidak valid.")

    def utc_bounds(self) -> tuple[datetime, datetime]:
        self.validate()
        local_tz = timezone(timedelta(hours=self.utc_offset_hours))
        start_local = datetime.combine(self.start_date, time.min, tzinfo=local_tz)
        end_exclusive_local = datetime.combine(
            self.end_date + timedelta(days=1), time.min, tzinfo=local_tz
        )
        return (
            start_local.astimezone(timezone.utc),
            end_exclusive_local.astimezone(timezone.utc),
        )

    def build_fql(self) -> str:
        start_utc, end_exclusive_utc = self.utc_bounds()
        start_text = start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_text = end_exclusive_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        base = (
            f"{self.time_field}:>='{start_text}'"
            f"+{self.time_field}:<'{end_text}'"
        )
        extra = (self.additional_fql or "").strip()
        return f"({base})+({extra})" if extra else base

    def metadata(self, credentials: FalconCredentials | None) -> dict[str, object]:
        start_utc, end_utc = self.utc_bounds()
        return {
            "customer_name": self.customer_name,
            "report_label": self.report_label,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "utc_offset_hours": self.utc_offset_hours,
            "start_utc": start_utc.isoformat(),
            "end_exclusive_utc": end_utc.isoformat(),
            "time_field": self.time_field,
            "additional_fql": self.additional_fql or "",
            "max_records": self.max_records,
            "page_size": self.page_size,
            "base_url": credentials.base_url if credentials else "SAMPLE",
            "member_cid": credentials.member_cid if credentials and credentials.member_cid else "",
        }
