from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class FalconConnection:
    """Ephemeral CrowdStrike connection settings.

    Credentials are intentionally held only in memory. The project exporter never
    serializes ``client_secret``.
    """

    client_id: str
    client_secret: str
    base_url: str = "us-1"
    member_cid: str | None = None

    @classmethod
    def from_env(cls) -> "FalconConnection":
        client_id = (os.getenv("FALCON_CLIENT_ID") or "").strip()
        client_secret = (os.getenv("FALCON_CLIENT_SECRET") or "").strip()
        if not client_id or not client_secret:
            raise ValueError("FALCON_CLIENT_ID dan FALCON_CLIENT_SECRET belum diisi.")
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            base_url=(os.getenv("FALCON_BASE_URL") or "us-1").strip(),
            member_cid=(os.getenv("FALCON_MEMBER_CID") or "").strip() or None,
        )

    def falconpy_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "base_url": self.base_url,
            "user_agent": "seraphim-falcon-data-collector/15.0.6.2",
        }
        if self.member_cid:
            kwargs["member_cid"] = self.member_cid
        return kwargs

    def safe_dict(self) -> dict[str, Any]:
        return {
            "client_id_suffix": self.client_id[-6:] if self.client_id else "",
            "base_url": self.base_url,
            "member_cid": self.member_cid,
        }
