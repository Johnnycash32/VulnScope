from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CertWatchCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=256)


class CertWatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    domain: str
    issuer: str | None
    expiry_date: datetime | None
    status: str
    days_remaining: int | None
    ssl_grade: str | None = None
    last_checked: datetime | None
    created_at: datetime


class CertWatchCheck(BaseModel):
    domain: str = Field(min_length=1, max_length=256)


class CertWatchResult(BaseModel):
    domain: str
    issuer: str | None
    expiry_date: datetime | None
    status: Literal["valid", "expiring_soon", "expired", "unknown", "error"]
    days_remaining: int | None
    ssl_grade: str | None = None
    error: str | None = None
