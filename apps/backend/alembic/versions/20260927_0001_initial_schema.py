"""Create the initial Cloud Detective schema.

Revision ID: 20260927_0001
Revises:
Create Date: 2026-09-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260927_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    severity = postgresql.ENUM(
        "NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity", create_type=False
    )
    finding_status = postgresql.ENUM(
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE",
        name="finding_status",
        create_type=False,
    )
    response_mode = postgresql.ENUM(
        "DRY_RUN", "ENFORCE", name="response_mode", create_type=False
    )
    severity.create(op.get_bind(), checkfirst=True)
    finding_status.create(op.get_bind(), checkfirst=True)
    response_mode.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_name", sa.String(length=128), nullable=False),
        sa.Column("event_source", sa.String(length=128), nullable=False),
        sa.Column("aws_region", sa.String(length=32), nullable=False),
        sa.Column("principal_arn", sa.Text(), nullable=True),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column("principal_name", sa.String(length=256), nullable=True),
        sa.Column("source_address", sa.Text(), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("source_kind", sa.String(length=16), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("resources", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("request_params", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("read_only", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("mfa_authenticated", sa.Boolean(), nullable=True),
        sa.Column("raw", postgresql.JSONB(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("partially_parsed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("parse_warnings", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )
    op.create_index("ix_events_event_time", "events", [sa.text("event_time DESC")])
    op.create_index("ix_events_principal_time", "events", ["principal_arn", "event_time"])
    op.create_index("ix_events_event_name", "events", ["event_name"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])
    op.create_index(
        "ix_events_error_code_present",
        "events",
        ["error_code"],
        postgresql_where=sa.text("error_code IS NOT NULL"),
    )

    op.create_table(
        "rules",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("rule_type", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("base_score", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("suppress_principals", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("playbook_id", sa.String(length=64), nullable=True),
        sa.Column("mitre_technique", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("group_key", sa.Text(), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("score_breakdown", postgresql.JSONB(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("principal_arn", sa.Text(), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("affected_resources", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", finding_status, nullable=False, server_default="OPEN"),
        sa.Column("assigned_to", sa.String(length=128), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["rule_id"], ["rules.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id", "group_key", "window_start", name="uq_finding_window"),
    )
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_principal_arn", "findings", ["principal_arn"])
    op.create_index("ix_findings_created_at", "findings", [sa.text("created_at DESC")])

    op.create_table(
        "finding_events",
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False, server_default="trigger"),
        sa.ForeignKeyConstraint(["event_id"], ["events.event_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id", "event_id"),
    )

    op.create_table(
        "principal_baselines",
        sa.Column("principal_arn", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_events", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("observed_ips", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("observed_countries", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("hourly_mean", sa.Numeric(), nullable=False, server_default="0"),
        sa.Column("hourly_stddev", sa.Numeric(), nullable=False, server_default="0"),
        sa.Column("total_events", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("principal_arn"),
    )

    op.create_table(
        "response_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("playbook_id", sa.String(length=64), nullable=False),
        sa.Column("target_arn", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("mode", response_mode, nullable=False),
        sa.Column("decision", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=64), nullable=True),
        sa.Column("previous_state", postgresql.JSONB(), nullable=True),
        sa.Column("aws_request_id", sa.String(length=128), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_index("ix_response_actions_finding_id", "response_actions", ["finding_id"])


def downgrade() -> None:
    op.drop_table("response_actions")
    op.drop_table("principal_baselines")
    op.drop_table("finding_events")
    op.drop_table("findings")
    op.drop_table("rules")
    op.drop_table("events")
    postgresql.ENUM(name="response_mode").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="finding_status").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="severity").drop(op.get_bind(), checkfirst=True)
