from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    verification_method: Literal["file", "dns"] = "file"


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    url: str
    verification_token: str
    verification_method: str
    verified_at: datetime | None
    created_at: datetime


class TargetCreated(BaseModel):
    target_id: int
    token: str
    verification_url: str
    instructions: str