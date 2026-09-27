from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from cloud_detective.detection.baseline import BaselineTracker
from cloud_detective.detection.loader import load_rules
from cloud_detective.detection.matching import context_matches, event_matches
from cloud_detective.detection.models import EventContext, Severity
from cloud_detective.detection.scoring import assess_risk, severity_for
from cloud_detective.schemas.events import CanonicalEvent, PrincipalType


def event(**overrides: Any) -> CanonicalEvent:
    values: dict[str, Any] = {
        "event_id": uuid4(),
        "event_time": datetime(2026, 9, 28, 3, 0, tzinfo=UTC),
        "event_name": "RunInstances",
        "event_source": "ec2.amazonaws.com",
        "aws_region": "ap-south-1",
        "principal_arn": "arn:aws:iam::111122223333:user/alice",
        "principal_type": PrincipalType.IAM_USER,
        "source_ip": "203.0.113.10",
        "mfa_authenticated": False,
        "raw": {},
    }
    values.update(overrides)
    return CanonicalEvent(**values)


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0, Severity.NORMAL),
        (19.99, Severity.NORMAL),
        (20, Severity.LOW),
        (39.99, Severity.LOW),
        (40, Severity.MEDIUM),
        (59.99, Severity.MEDIUM),
        (60, Severity.HIGH),
        (79.99, Severity.HIGH),
        (80, Severity.CRITICAL),
        (100, Severity.CRITICAL),
    ],
)
def test_severity_boundaries(score: float, severity: Severity) -> None:
    assert severity_for(score) is severity


def test_risk_score_is_explainable_and_capped() -> None:
    assessment = assess_risk(
        85,
        event(principal_type=PrincipalType.ROOT),
        EventContext(
            known_bad_origin=True,
            security_critical_resource=True,
            country="DE",
            country_seen=False,
            ip_seen=False,
        ),
    )
    assert assessment.score == 100
    assert assessment.severity is Severity.CRITICAL
    assert assessment.factors == {
        "base": 85.0,
        "principal": 2.0,
        "resource": 1.8,
        "time": 1.0,
        "origin": 2.5,
        "mfa": 1.4,
    }


def test_baseline_warmup_and_incremental_history() -> None:
    started = datetime(2026, 9, 27, 0, 0, tzinfo=UTC)
    tracker = BaselineTracker(started, warmup_hours=24)
    first = event(event_time=started + timedelta(hours=1))

    cold_context = tracker.context_for(first, country="IN")
    assert cold_context.baseline_warmed is False
    assert cold_context.api_seen is False
    assert cold_context.country_seen is False

    tracker.update(first, country="IN")
    later = event(event_time=started + timedelta(hours=25))
    warm_context = tracker.context_for(later, country="IN")
    assert warm_context.baseline_warmed is True
    assert warm_context.api_seen is True
    assert warm_context.country_seen is True
    assert warm_context.ip_seen is True
    assert warm_context.region_seen is True


def test_baseline_detects_hourly_rate_anomaly() -> None:
    started = datetime(2026, 9, 25, tzinfo=UTC)
    tracker = BaselineTracker(started, warmup_hours=24)
    tracker.update(event(event_time=started + timedelta(hours=1)))
    tracker.update(event(event_time=started + timedelta(hours=2)))
    burst_hour = started + timedelta(hours=30)
    for minute in range(5):
        tracker.update(event(event_time=burst_hour + timedelta(minutes=minute)))

    assert tracker.context_for(event(event_time=burst_hour + timedelta(minutes=6))).rate_anomaly


def test_unknown_rule_predicates_fail_closed() -> None:
    with pytest.raises(ValueError, match="unsupported event predicates"):
        event_matches({"event_nmae": ["RunInstances"]}, event())
    with pytest.raises(ValueError, match="unsupported context predicates"):
        context_matches([{"new_contry": True}], EventContext())


def test_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        """
rules:
  - &rule
    id: duplicate
    name: Duplicate
    category: test
    type: signature
    description: test
    base_score: 10
  - *rule
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate rule id"):
        load_rules(rules)

