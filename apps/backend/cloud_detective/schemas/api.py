from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class FindingView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    severity: str
    risk_score: Decimal
    title: str
    description: str
    principal_arn: str | None
    source_ip: IPvAnyAddress | None
    affected_resources: list[str]
    status: str
    assigned_to: str | None
    notes: str | None
    created_at: datetime


class FindingEvidenceView(BaseModel):
    event_id: UUID
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    principal_arn: str | None
    source_address: str | None
    mfa_authenticated: bool | None
    error_code: str | None
    simulated: bool


class FindingExplanation(BaseModel):
    finding: FindingView
    rule_name: str
    rule_type: str
    rule_description: str
    category: str
    mitre_technique: str | None
    score_factors: dict[str, float]
    window_start: datetime
    window_end: datetime
    event_count: int
    evidence: list[FindingEvidenceView]
    evidence_truncated: bool


class EventView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: UUID
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    principal_arn: str | None
    source_address: str | None
    error_code: str | None
    read_only: bool
    partially_parsed: bool


class RuleView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    rule_type: str
    category: str
    base_score: int
    enabled: bool
    playbook_id: str | None
    mitre_technique: str | None


class FindingUpdate(BaseModel):
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    assigned_to: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, max_length=4000)


class DashboardSummary(BaseModel):
    total_events: int
    open_findings: int
    enabled_rules: int
    severity_counts: dict[str, int]
    response_mode: str


class IngestResult(BaseModel):
    accepted: bool
    duplicate: bool
    finding_ids: list[UUID]
    warnings: list[str]


class ResponseRequest(BaseModel):
    playbook_id: str
    target_arn: str
    confirmation: Literal["DRY_RUN", "ENFORCE"] = "DRY_RUN"


class ResponseResult(BaseModel):
    action_id: UUID
    mode: str
    decision: str
    outcome: str
    preview: dict[str, Any]
