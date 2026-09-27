from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.dialects import postgresql

from cloud_detective.detection.models import (
    FindingCandidate,
    RiskAssessment,
    RuleDefinition,
    Severity,
)
from cloud_detective.detection.persistence import persist_event, persist_finding, sync_rule_catalog
from cloud_detective.schemas.events import CanonicalEvent


class FakeResult:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value


class FakeSession:
    def __init__(self, results: list[Any] | None = None) -> None:
        self.results = list(results or [])
        self.sql: list[str] = []

    def execute(self, statement: Any) -> FakeResult:
        self.sql.append(str(statement.compile(dialect=postgresql.dialect())))
        return FakeResult(self.results.pop(0) if self.results else None)


def sample_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_time=datetime(2026, 9, 28, tzinfo=UTC),
        event_name="StopLogging",
        event_source="cloudtrail.amazonaws.com",
        aws_region="ap-south-1",
        raw={},
    )


def test_rule_catalog_compiles_postgres_upsert() -> None:
    session = FakeSession()
    rule = RuleDefinition(
        id="test-rule",
        name="Test rule",
        category="test",
        type="signature",
        description="Test",
        base_score=50,
    )
    sync_rule_catalog(session, [rule])  # type: ignore[arg-type]
    assert "ON CONFLICT (id) DO UPDATE" in session.sql[0]


def test_event_insert_ignores_duplicate_ids() -> None:
    item = sample_event()
    inserted = FakeSession([item.event_id])
    duplicate = FakeSession([None])
    assert persist_event(inserted, item) is True  # type: ignore[arg-type]
    assert persist_event(duplicate, item) is False  # type: ignore[arg-type]
    assert "ON CONFLICT (event_id) DO NOTHING" in inserted.sql[0]


def test_finding_insert_links_contributing_events() -> None:
    event_id = uuid4()
    finding_id = uuid4()
    candidate = FindingCandidate(
        rule_id="cloudtrail-tampering",
        rule_name="CloudTrail tampering",
        category="defence-evasion",
        title="CloudTrail tampering",
        description="Logging was stopped.",
        group_key="alice",
        window_start=datetime(2026, 9, 28, tzinfo=UTC),
        window_end=datetime(2026, 9, 28, tzinfo=UTC),
        event_ids=[event_id],
        risk=RiskAssessment(
            score=85,
            severity=Severity.CRITICAL,
            factors={"base": 85.0},
        ),
        dedupe_key="stable-key",
    )
    session = FakeSession([finding_id, None])
    result = persist_finding(session, candidate)  # type: ignore[arg-type]
    assert result == finding_id
    assert len(session.sql) == 2
    assert "ON CONFLICT (rule_id, group_key, window_start) DO NOTHING" in session.sql[0]
    assert "ON CONFLICT (finding_id, event_id) DO NOTHING" in session.sql[1]


def test_duplicate_finding_does_not_link_events() -> None:
    candidate = FindingCandidate(
        rule_id="test",
        rule_name="Test",
        category="test",
        title="Test",
        description="Test",
        group_key="global",
        window_start=datetime(2026, 9, 28, tzinfo=UTC),
        window_end=datetime(2026, 9, 28, tzinfo=UTC),
        event_ids=[UUID("00000000-0000-0000-0000-000000000001")],
        risk=RiskAssessment(score=40, severity=Severity.MEDIUM, factors={"base": 40}),
        dedupe_key="duplicate",
    )
    session = FakeSession([None])
    assert persist_finding(session, candidate) is None  # type: ignore[arg-type]
    assert len(session.sql) == 1

