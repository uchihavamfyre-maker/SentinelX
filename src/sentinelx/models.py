"""Validated event and alert models."""
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

EventType = Literal["login_success", "login_failure"]
Label = Literal["normal", "suspicious"]

class AuthEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    source_ip: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=128)
    event_type: EventType
    label: Label | None = None

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

class DetectionAlert(BaseModel):
    alert_id: str
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    source_ip: str
    username: str
    first_seen: datetime
    last_seen: datetime
    event_count: int = Field(ge=1)
    evidence_event_ids: list[str]
    explanation: str

class EvaluationMetrics(BaseModel):
    total_events: int
    labeled_events: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
