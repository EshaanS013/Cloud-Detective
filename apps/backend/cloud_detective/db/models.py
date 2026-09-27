from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from cloud_detective.db.base import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), unique=True, index=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_name: Mapped[str] = mapped_column(String(128), index=True)
    event_source: Mapped[str] = mapped_column(String(128))
    aws_region: Mapped[str] = mapped_column(String(32))
    principal_arn: Mapped[str | None] = mapped_column(Text, index=True)
    principal_type: Mapped[str] = mapped_column(String(32))
    principal_name: Mapped[str | None] = mapped_column(String(256))
    source_address: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(INET, index=True)
    source_kind: Mapped[str] = mapped_column(String(16))
    user_agent: Mapped[str | None] = mapped_column(Text)
    resources: Mapped[list[str]] = mapped_column(JSONB, default=list)
    request_params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(128), index=True)
    error_message: Mapped[str | None] = mapped_column(Text)
    read_only: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_authenticated: Mapped[bool | None] = mapped_column(Boolean)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    partially_parsed: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    rule_type: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(64))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    base_score: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    suppress_principals: Mapped[list[str]] = mapped_column(JSONB, default=list)
    playbook_id: Mapped[str | None] = mapped_column(String(64))
    mitre_technique: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("rule_id", "group_key", "window_start"),)

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), index=True)
    group_key: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(
        Enum("NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity")
    )
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(JSONB)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    principal_arn: Mapped[str | None] = mapped_column(Text, index=True)
    source_ip: Mapped[str | None] = mapped_column(INET)
    affected_resources: Mapped[list[str]] = mapped_column(JSONB, default=list)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        Enum("OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", name="finding_status"),
        default="OPEN",
    )
    assigned_to: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvent(Base):
    __tablename__ = "finding_events"

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(16), default="trigger")


class PrincipalBaseline(Base):
    __tablename__ = "principal_baselines"

    principal_arn: Mapped[str] = mapped_column(Text, primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observed_events: Mapped[list[str]] = mapped_column(JSONB, default=list)
    observed_ips: Mapped[list[str]] = mapped_column(JSONB, default=list)
    observed_countries: Mapped[list[str]] = mapped_column(JSONB, default=list)
    hourly_mean: Mapped[Decimal] = mapped_column(Numeric, default=0)
    hourly_stddev: Mapped[Decimal] = mapped_column(Numeric, default=0)
    total_events: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    playbook_id: Mapped[str] = mapped_column(String(64))
    target_arn: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(128))
    mode: Mapped[str] = mapped_column(Enum("DRY_RUN", "ENFORCE", name="response_mode"))
    decision: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str | None] = mapped_column(String(64))
    previous_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    aws_request_id: Mapped[str | None] = mapped_column(String(128))
    error_detail: Mapped[str | None] = mapped_column(Text)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
