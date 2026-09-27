from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleType(StrEnum):
    SIGNATURE = "signature"
    THRESHOLD = "threshold"
    CONTEXTUAL = "contextual"
    SEQUENCE = "sequence"


class Severity(StrEnum):
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str
    type: RuleType
    description: str
    base_score: int = Field(ge=0, le=100)
    enabled: bool = True
    match: dict[str, Any] = Field(default_factory=dict)
    group_by: str | None = None
    window_seconds: int | None = Field(default=None, gt=0)
    threshold: int | None = Field(default=None, gt=0)
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    suppress_principals: list[str] = Field(default_factory=list)
    playbook_id: str | None = None
    mitre_technique: str | None = None

    @model_validator(mode="after")
    def validate_type_fields(self) -> "RuleDefinition":
        if self.type is RuleType.THRESHOLD and (
            not self.group_by or not self.window_seconds or not self.threshold
        ):
            raise ValueError("threshold rules require group_by, window_seconds and threshold")
        if self.type is RuleType.SEQUENCE and (
            not self.group_by or not self.window_seconds or len(self.steps) < 2
        ):
            raise ValueError(
                "sequence rules require group_by, window_seconds and at least 2 steps"
            )
        if self.type is RuleType.CONTEXTUAL and not self.conditions:
            raise ValueError("contextual rules require conditions")
        return self


class EventContext(BaseModel):
    country: str | None = None
    known_bad_origin: bool = False
    production_resource: bool = False
    security_critical_resource: bool = False
    baseline_warmed: bool = True
    api_seen: bool = True
    country_seen: bool = True
    ip_seen: bool = True
    region_seen: bool = True
    rate_anomaly: bool = False


class RiskAssessment(BaseModel):
    score: float
    severity: Severity
    factors: dict[str, float]


class FindingCandidate(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    title: str
    description: str
    group_key: str
    window_start: datetime
    window_end: datetime
    event_ids: list[UUID]
    risk: RiskAssessment
    dedupe_key: str
    playbook_id: str | None = None
    mitre_technique: str | None = None

