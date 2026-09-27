from cloud_detective.db.base import Base
from cloud_detective.db.models import (
    Event,
    Finding,
    FindingEvent,
    PrincipalBaseline,
    ResponseAction,
    Rule,
)


def test_initial_schema_contains_required_tables() -> None:
    assert set(Base.metadata.tables) == {
        "events",
        "rules",
        "findings",
        "finding_events",
        "principal_baselines",
        "response_actions",
    }
    assert Event.__table__.c.event_id.unique
    assert ResponseAction.__table__.c.idempotency_key.unique
    assert Rule.__table__.c.enabled.default.arg is True
    assert FindingEvent.__table__.primary_key.columns.keys() == ["finding_id", "event_id"]
    assert PrincipalBaseline.__table__.c.principal_arn.primary_key
    assert Finding.__table__.c.group_key.nullable is False
